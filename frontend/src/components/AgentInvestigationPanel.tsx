import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import { SeverityBadge } from './Badge'
import type {
  AgentProgressEvent,
  AgentRunDetail,
  AgentRunSummary,
  AnalystFeedback,
  FeedbackRating,
  IncidentMemory,
  ProposedAction,
  ProposedActionReviewStatus,
  ProposedActionStatus,
} from '../api/types'

const FEEDBACK_OPTIONS: { value: FeedbackRating; label: string }[] = [
  { value: 'accurate', label: '👍 Accurate' },
  { value: 'false_positive', label: '👎 False Positive' },
  { value: 'missed_detection', label: '⚠️ Missed Something' },
]

const AGENT_ORDER = ['detection', 'investigation', 'threat_intel', 'risk', 'response', 'report']

const AGENT_LABELS: Record<string, string> = {
  detection: 'Detection Agent',
  investigation: 'Investigation Agent',
  threat_intel: 'Threat Intel Agent',
  risk: 'Risk Agent',
  response: 'Response Agent',
  report: 'Report Agent',
}

type LiveStage = 'waiting' | 'running' | 'done' | 'failed'

const LIVE_STAGE_ICON: Record<LiveStage, string> = {
  waiting: '⚪',
  running: '🟡',
  done: '🟢',
  failed: '🔴',
}

const ACTION_STATUS_STYLES: Record<ProposedActionStatus, string> = {
  pending: 'bg-amber-600/80 text-amber-50',
  approved: 'bg-emerald-700/80 text-emerald-50',
  rejected: 'bg-slate-700 text-slate-300',
  executed: 'bg-indigo-700/80 text-indigo-50',
  execution_failed: 'bg-red-800/80 text-red-50',
}

function ActionStatusBadge({ status }: { status: ProposedActionStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide ${ACTION_STATUS_STYLES[status]}`}>
      {status}
    </span>
  )
}

interface Props {
  incidentId: number
  canAct: boolean
}

export function AgentInvestigationPanel({ incidentId, canAct }: Props) {
  const [runs, setRuns] = useState<AgentRunSummary[]>([])
  const [selectedRun, setSelectedRun] = useState<AgentRunDetail | null>(null)
  const [loadingRuns, setLoadingRuns] = useState(true)
  const [investigating, setInvestigating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [actions, setActions] = useState<ProposedAction[]>([])
  const [reviewingId, setReviewingId] = useState<number | null>(null)
  const [executingId, setExecutingId] = useState<number | null>(null)
  const [memory, setMemory] = useState<IncidentMemory | null>(null)
  const [feedback, setFeedback] = useState<AnalystFeedback[]>([])
  const [feedbackNote, setFeedbackNote] = useState('')
  const [submittingFeedback, setSubmittingFeedback] = useState(false)
  const [liveStages, setLiveStages] = useState<Record<string, LiveStage> | null>(null)

  async function loadRuns(): Promise<AgentRunSummary[]> {
    setLoadingRuns(true)
    try {
      const res = await api.listAgentRuns(incidentId)
      setRuns(res.runs)
      return res.runs
    } finally {
      setLoadingRuns(false)
    }
  }

  async function loadActions() {
    const res = await api.listProposedActions(incidentId)
    setActions(res.actions)
  }

  async function loadFeedback() {
    const res = await api.listIncidentFeedback(incidentId)
    setFeedback(res.feedback)
  }

  async function openRun(runId: number) {
    setError(null)
    try {
      setSelectedRun(await api.getAgentRun(runId))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load agent run')
    }
  }

  useEffect(() => {
    void loadRuns().then((loaded) => {
      const latest = loaded.find((r) => r.status === 'completed') ?? loaded[0]
      if (latest) void openRun(latest.id)
    })
    void loadActions()
    void loadFeedback()
    // Free (local embedding search, no LLM call) - same institutional
    // memory the agents themselves read from before investigating.
    api
      .getIncidentMemory(incidentId)
      .then(setMemory)
      .catch(() => setMemory(null))
    // Only re-run when navigating to a different incident.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId])

  async function runInvestigation() {
    setInvestigating(true)
    setError(null)
    setLiveStages(Object.fromEntries(AGENT_ORDER.map((agent) => [agent, 'waiting' as LiveStage])))

    try {
      const { run_id } = await api.investigateIncidentLive(incidentId)

      // Dispatches to a Celery worker and streams each agent's progress
      // over this WebSocket as it completes - the 🟢/🟡/⚪ status strip
      // below renders live instead of only showing a result once the
      // whole ~8-10s chain finishes.
      await new Promise<void>((resolve) => {
        const ws = new WebSocket(api.agentRunWsUrl(run_id))
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data) as AgentProgressEvent
          if (data.type === 'started') {
            setLiveStages((prev) => (prev ? { ...prev, [AGENT_ORDER[0]]: 'running' } : prev))
          } else if (data.type === 'agent_completed' && data.agent) {
            const completedAgent = data.agent
            setLiveStages((prev) => {
              if (!prev) return prev
              const next: Record<string, LiveStage> = { ...prev, [completedAgent]: 'done' }
              const nextAgent = AGENT_ORDER[AGENT_ORDER.indexOf(completedAgent) + 1]
              if (nextAgent) next[nextAgent] = 'running'
              return next
            })
          } else if (data.type === 'failed' || data.type === 'error') {
            setError(data.error ?? 'Investigation failed')
            setLiveStages((prev) => {
              if (!prev) return prev
              const next = { ...prev }
              for (const agent of AGENT_ORDER) if (next[agent] === 'running') next[agent] = 'failed'
              return next
            })
          }
          if (data.type === 'completed' || data.type === 'failed' || data.type === 'error') {
            ws.close()
          }
        }
        ws.onclose = () => resolve()
        ws.onerror = () => resolve()
      })

      await loadRuns()
      await openRun(run_id)
      await loadActions()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Investigation failed')
      await loadRuns()
    } finally {
      setInvestigating(false)
      setLiveStages(null)
    }
  }

  async function review(actionId: number, status: ProposedActionReviewStatus) {
    setReviewingId(actionId)
    setError(null)
    try {
      const updated = await api.reviewProposedAction(actionId, status)
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to review action')
    } finally {
      setReviewingId(null)
    }
  }

  async function execute(actionId: number) {
    setExecutingId(actionId)
    setError(null)
    try {
      const updated = await api.executeProposedAction(actionId)
      setActions((prev) => prev.map((a) => (a.id === updated.id ? updated : a)))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to execute action')
    } finally {
      setExecutingId(null)
    }
  }

  async function submitFeedback(rating: FeedbackRating) {
    setSubmittingFeedback(true)
    setError(null)
    try {
      await api.submitIncidentFeedback(incidentId, {
        rating,
        note: feedbackNote.trim() || undefined,
        agent_run_id: selectedRun?.id,
      })
      setFeedbackNote('')
      await loadFeedback()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to submit feedback')
    } finally {
      setSubmittingFeedback(false)
    }
  }

  const result = selectedRun?.result
  const messages = selectedRun?.messages ?? []

  return (
    <div className="rounded-xl border border-violet-900/60 bg-violet-950/20 p-5 space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-medium text-violet-300">AI Security Team</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Detection &rarr; Investigation &rarr; Threat Intel &rarr; Risk &rarr; Response &rarr; Report
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void runInvestigation()}
            disabled={investigating}
            className="rounded-lg border border-violet-700 hover:bg-violet-900/40 disabled:opacity-50 text-xs px-3 py-1.5 transition text-violet-300"
          >
            {investigating ? 'Investigating...' : runs.length > 0 ? 'Run Again' : 'Run Multi-Agent Investigation'}
          </button>
        )}
      </div>

      {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

      {liveStages && (
        <div className="flex flex-wrap gap-2">
          {AGENT_ORDER.map((agent) => (
            <span
              key={agent}
              className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border border-slate-700 bg-slate-900/60 text-slate-300"
            >
              <span>{LIVE_STAGE_ICON[liveStages[agent]]}</span>
              {AGENT_LABELS[agent]}
            </span>
          ))}
        </div>
      )}

      {memory &&
        (memory.similar_past_incidents.length > 0 ||
          memory.repeat_hosts.length > 0 ||
          memory.repeat_users.length > 0 ||
          memory.recent_corrections.length > 0) && (
        <div>
          <h3 className="text-xs uppercase tracking-wide text-slate-500 mb-2">
            Institutional Memory <span className="normal-case text-slate-600">&mdash; what the team already knows</span>
          </h3>
          <div className="space-y-2">
            {memory.similar_past_incidents.map((s) => (
              <Link
                key={`similar-${s.incident_id}`}
                to={`/incidents/${s.incident_id}`}
                className="flex items-start justify-between gap-3 text-sm rounded-lg border border-slate-800 bg-slate-900/60 p-3 hover:border-violet-800 transition"
              >
                <div className="min-w-0">
                  <p className="text-slate-200 truncate">
                    Similar past incident: <span className="text-violet-300">{s.title}</span>
                  </p>
                  {s.prior_report_summary && <p className="text-xs text-slate-500 mt-0.5">{s.prior_report_summary}</p>}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {s.similarity !== null && (
                    <span className="text-xs text-slate-500">{Math.round(s.similarity * 100)}% similar</span>
                  )}
                  <SeverityBadge severity={s.risk_level} />
                </div>
              </Link>
            ))}
            {[...memory.repeat_hosts, ...memory.repeat_users].map((r, i) => (
              <Link
                key={`repeat-${r.incident_id}-${i}`}
                to={`/incidents/${r.incident_id}`}
                className="flex items-start justify-between gap-3 text-sm rounded-lg border border-amber-900/60 bg-amber-950/10 p-3 hover:border-amber-700 transition"
              >
                <div className="min-w-0">
                  <p className="text-slate-200 truncate">
                    Repeat involvement: <span className="text-amber-300">{r.shared.join(', ')}</span> also seen in{' '}
                    <span className="text-slate-300">{r.title}</span>
                  </p>
                </div>
                <SeverityBadge severity={r.risk_level} />
              </Link>
            ))}
            {memory.recent_corrections.map((c) => (
              <Link
                key={`correction-${c.incident_id}`}
                to={`/incidents/${c.incident_id}`}
                className="flex items-start justify-between gap-3 text-sm rounded-lg border border-sky-900/60 bg-sky-950/10 p-3 hover:border-sky-700 transition"
              >
                <div className="min-w-0">
                  <p className="text-slate-200 truncate">
                    Analyst feedback ({c.rating.replace('_', ' ')}) on <span className="text-sky-300">{c.incident_title}</span>
                  </p>
                  <p className="text-xs text-slate-500 mt-0.5">{c.note}</p>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {!loadingRuns && runs.length === 0 && !investigating && (
        <p className="text-sm text-slate-500">
          No investigations run yet. Kick off the AI Security Team to have six specialized agents independently
          detect, investigate, enrich, score, and respond to this incident - each reading what the ones before it
          found.
        </p>
      )}

      {runs.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {runs.map((run) => (
            <button
              key={run.id}
              onClick={() => void openRun(run.id)}
              className={`text-xs px-2.5 py-1 rounded-lg border transition ${
                selectedRun?.id === run.id
                  ? 'border-violet-600 bg-violet-900/40 text-violet-200'
                  : 'border-slate-700 text-slate-400 hover:bg-slate-800'
              }`}
            >
              Run #{run.id} &middot; {run.status} &middot; {run.started_at}
            </button>
          ))}
        </div>
      )}

      {selectedRun?.error && (
        <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">
          Run #{selectedRun.id} failed: {selectedRun.error}
        </p>
      )}

      {messages.length > 0 && (
        <div>
          <h3 className="text-xs uppercase tracking-wide text-slate-500 mb-2">Agent Conversation</h3>
          <ol className="space-y-2 max-h-72 overflow-y-auto pr-1">
            {messages.map((m, i) => (
              <li key={m.id ?? i} className="text-sm border-l-2 border-violet-900 pl-3">
                <p className="text-xs font-medium text-violet-300">{AGENT_LABELS[m.agent] ?? m.agent}</p>
                <p className="text-slate-300">{m.content}</p>
              </li>
            ))}
          </ol>
        </div>
      )}

      {result && (
        <div className="grid md:grid-cols-2 gap-4">
          {result.detection && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs font-medium text-violet-300 mb-1">Detection</p>
              <p className="text-sm text-slate-300">{result.detection.assessment}</p>
              <p className="text-xs text-slate-500 mt-2">
                Pattern: {result.detection.attack_pattern} &middot; Confidence: {result.detection.confidence}%
              </p>
            </div>
          )}
          {result.investigation && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs font-medium text-violet-300 mb-1">Investigation</p>
              <p className="text-sm text-slate-300">{result.investigation.timeline_narrative}</p>
              <p className="text-xs text-slate-500 mt-2">Objective: {result.investigation.attacker_objective}</p>
            </div>
          )}
          {result.threat_intel_findings && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <p className="text-xs font-medium text-violet-300 mb-1">Threat Intelligence</p>
              <p className="text-sm text-slate-300">{result.threat_intel_findings.summary}</p>
              {result.threat_intel_findings.mitre_techniques.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {result.threat_intel_findings.mitre_techniques.map((t) => (
                    <li key={t.id} className="text-xs text-slate-400">
                      <span className="font-mono text-slate-300">{t.id}</span> {t.name} &mdash; {t.evidence}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {result.risk && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center gap-2 mb-1">
                <p className="text-xs font-medium text-violet-300">Business Risk</p>
                <SeverityBadge severity={result.risk.business_risk_level} />
              </div>
              <p className="text-sm text-slate-300">{result.risk.explanation}</p>
              <p className="text-xs text-slate-500 mt-2">
                Score: {result.risk.business_risk_score}/100
                {result.risk.most_critical_asset && ` · Most critical asset: ${result.risk.most_critical_asset}`}
              </p>
            </div>
          )}
        </div>
      )}

      {result?.report && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-2">
          <p className="text-xs font-medium text-violet-300">Final Report</p>
          <p className="text-sm text-slate-300">{result.report.executive_summary}</p>
          <p className="text-sm text-slate-400">{result.report.technical_summary}</p>
          <p className="text-xs text-slate-500">Compliance: {result.report.compliance_notes}</p>
          <p className="text-xs text-slate-500">Customer notification: {result.report.customer_notification}</p>
        </div>
      )}

      {selectedRun && (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-3">
          <div>
            <p className="text-xs font-medium text-violet-300">Learning Loop - Rate This Investigation</p>
            <p className="text-xs text-slate-500 mt-0.5">
              Corrections you note here are fed back into future investigations as institutional memory.
            </p>
          </div>
          {canAct && (
            <div className="space-y-2">
              <textarea
                value={feedbackNote}
                onChange={(e) => setFeedbackNote(e.target.value)}
                placeholder="Optional note - especially useful for false positives or missed detections"
                rows={2}
                className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600"
              />
              <div className="flex flex-wrap gap-2">
                {FEEDBACK_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => void submitFeedback(opt.value)}
                    disabled={submittingFeedback}
                    className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-xs px-2.5 py-1.5 text-slate-300 transition"
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          )}
          {feedback.length > 0 && (
            <ul className="space-y-1.5 pt-1">
              {feedback.map((f) => (
                <li key={f.id} className="text-xs text-slate-400">
                  <span className="text-slate-300">{FEEDBACK_OPTIONS.find((o) => o.value === f.rating)?.label ?? f.rating}</span>
                  {' by '}
                  {f.reviewed_by_email}
                  {f.note && <span className="text-slate-500"> - {f.note}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {actions.length > 0 && (
        <div>
          <h3 className="text-xs uppercase tracking-wide text-slate-500 mb-2">
            Proposed Actions{result?.response ? ` (urgency: ${result.response.urgency})` : ''}
          </h3>
          <ul className="space-y-2">
            {actions.map((action) => (
              <li
                key={action.id}
                className="flex items-start justify-between gap-3 text-sm rounded-lg border border-slate-800 bg-slate-900/60 p-3"
              >
                <div className="min-w-0">
                  <span className="text-xs uppercase tracking-wide text-slate-500 mr-2">{action.category}</span>
                  <p className="text-slate-200 mt-0.5">{action.description}</p>
                  {action.reviewed_by_email && (
                    <p className="text-xs text-slate-500 mt-1">
                      {action.status} by {action.reviewed_by_email}
                    </p>
                  )}
                  {action.execution_result && (
                    <ul className="text-xs text-slate-500 mt-1 space-y-0.5">
                      {action.execution_result.map((r, i) => (
                        <li key={i} className={r.ok ? 'text-emerald-400' : 'text-red-400'}>
                          {r.integration}: {r.message}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {action.status === 'pending' && canAct ? (
                    <>
                      <button
                        onClick={() => void review(action.id, 'approved')}
                        disabled={reviewingId === action.id}
                        className="rounded-lg border border-emerald-700 hover:bg-emerald-900/40 disabled:opacity-50 text-xs px-2.5 py-1 text-emerald-300 transition"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => void review(action.id, 'rejected')}
                        disabled={reviewingId === action.id}
                        className="rounded-lg border border-red-800 hover:bg-red-900/40 disabled:opacity-50 text-xs px-2.5 py-1 text-red-300 transition"
                      >
                        Reject
                      </button>
                    </>
                  ) : action.status === 'approved' && canAct ? (
                    <>
                      <button
                        onClick={() => void execute(action.id)}
                        disabled={executingId === action.id}
                        className="rounded-lg border border-indigo-700 hover:bg-indigo-900/40 disabled:opacity-50 text-xs px-2.5 py-1 text-indigo-300 transition"
                      >
                        {executingId === action.id ? 'Executing...' : 'Execute'}
                      </button>
                      <ActionStatusBadge status={action.status} />
                    </>
                  ) : (
                    <ActionStatusBadge status={action.status} />
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
