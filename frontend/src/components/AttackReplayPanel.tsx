import { useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { SeverityBadge } from './Badge'
import type { AgentRunDetail, AgentRunSummary, EventItem } from '../api/types'

const AGENT_ORDER = ['detection', 'investigation', 'threat_intel', 'risk', 'response', 'report']

const AGENT_LABELS: Record<string, string> = {
  detection: 'Detection Agent',
  investigation: 'Investigation Agent',
  threat_intel: 'Threat Intel Agent',
  risk: 'Risk Agent',
  response: 'Response Agent',
  report: 'Report Agent',
}

const STEP_MS = 1800

type ReplayStep =
  | { kind: 'event'; event: EventItem }
  | { kind: 'agent'; agent: string }

interface Props {
  incidentId: number
  timeline: EventItem[]
}

export function AttackReplayPanel({ incidentId, timeline }: Props) {
  const [runs, setRuns] = useState<AgentRunSummary[]>([])
  const [selectedRun, setSelectedRun] = useState<AgentRunDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [index, setIndex] = useState(0)
  const [playing, setPlaying] = useState(false)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const { runs: list } = await api.listAgentRuns(incidentId)
        if (cancelled) return
        setRuns(list)
        const latestCompleted = [...list].reverse().find((r) => r.status === 'completed') ?? list[list.length - 1]
        if (latestCompleted) {
          setSelectedRun(await api.getAgentRun(latestCompleted.id))
        }
        setError(null)
      } catch (err) {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Failed to load investigation history')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [incidentId])

  async function selectRun(runId: number) {
    setIndex(0)
    setPlaying(false)
    try {
      setSelectedRun(await api.getAgentRun(runId))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load run')
    }
  }

  // Real chronology, not fabricated: the actual attack events (real
  // Event.timestamp, spread over however long the attack really took),
  // followed by the AI's real investigation stages (real AgentMessage/
  // result content, in the order the agents actually ran). These are two
  // genuinely different timescales - the AI investigates after the fact,
  // in a burst of seconds - and the replay doesn't pretend otherwise by
  // interleaving them as if the AI were reacting live.
  const steps: ReplayStep[] = useMemo(() => {
    const eventSteps: ReplayStep[] = timeline.map((event) => ({ kind: 'event', event }))
    const agentSteps: ReplayStep[] = AGENT_ORDER.filter(
      (agent) => selectedRun?.messages.some((m) => m.agent === agent) || (selectedRun?.result as Record<string, unknown> | undefined)?.[agent === 'threat_intel' ? 'threat_intel_findings' : agent]
    ).map((agent) => ({ kind: 'agent', agent }))
    return [...eventSteps, ...agentSteps]
  }, [timeline, selectedRun])

  useEffect(() => {
    setIndex(0)
    setPlaying(false)
  }, [steps.length])

  useEffect(() => {
    if (!playing) {
      if (timerRef.current) clearInterval(timerRef.current)
      return
    }
    timerRef.current = setInterval(() => {
      setIndex((i) => {
        if (i >= steps.length - 1) {
          setPlaying(false)
          return i
        }
        return i + 1
      })
    }, STEP_MS)
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [playing, steps.length])

  if (loading) return <p className="text-sm text-slate-500">Loading replay...</p>
  if (error) return <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>
  if (steps.length === 0) {
    return <p className="text-sm text-slate-500">Nothing to replay yet - ingest events and run an investigation first.</p>
  }

  const current = steps[index]
  const result = selectedRun?.result

  return (
    <div className="rounded-xl border border-amber-900/50 bg-amber-950/10 p-5 space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-medium text-amber-300">Attack Replay</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real recorded history, step by step - {timeline.length} real event{timeline.length === 1 ? '' : 's'}
            {selectedRun ? `, then the real AI investigation (run #${selectedRun.id})` : ''}.
          </p>
        </div>
        {runs.length > 1 && (
          <select
            value={selectedRun?.id ?? ''}
            onChange={(e) => void selectRun(Number(e.target.value))}
            className="text-xs rounded-lg border border-slate-700 bg-slate-900 px-2 py-1.5 text-slate-300"
          >
            {runs.map((r) => (
              <option key={r.id} value={r.id}>
                Run #{r.id} &middot; {r.status}
              </option>
            ))}
          </select>
        )}
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => setIndex((i) => Math.max(0, i - 1))}
          disabled={index === 0}
          className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-30 text-xs px-3 py-1.5 transition"
        >
          &larr; Back
        </button>
        <button
          onClick={() => setPlaying((p) => !p)}
          className="rounded-lg bg-amber-700 hover:bg-amber-600 text-white text-xs font-medium px-4 py-1.5 transition"
        >
          {playing ? 'Pause' : index >= steps.length - 1 ? 'Replay' : 'Play'}
        </button>
        <button
          onClick={() => setIndex((i) => (i >= steps.length - 1 ? 0 : i + 1))}
          disabled={index >= steps.length - 1}
          className="rounded-lg border border-slate-700 hover:bg-slate-800 disabled:opacity-30 text-xs px-3 py-1.5 transition"
        >
          Forward &rarr;
        </button>
        <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden">
          <div
            className="h-full bg-amber-600 transition-all"
            style={{ width: `${((index + 1) / steps.length) * 100}%` }}
          />
        </div>
        <span className="text-xs text-slate-500 shrink-0">
          {index + 1} / {steps.length}
        </span>
      </div>

      {current.kind === 'event' ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs uppercase tracking-wide text-slate-500">Real Event</span>
            <SeverityBadge severity={current.event.severity} />
          </div>
          <p className="text-sm text-slate-200">{current.event.message}</p>
          <p className="text-xs text-slate-500 mt-2">
            {current.event.timestamp} &middot; {current.event.host}
            {current.event.username && ` · ${current.event.username}`}
            {current.event.source_ip && ` · ${current.event.source_ip}`} &middot; {current.event.event_type}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-violet-900/60 bg-violet-950/10 p-4 space-y-2">
          <span className="text-xs uppercase tracking-wide text-violet-400">{AGENT_LABELS[current.agent]}</span>
          {selectedRun?.messages
            .filter((m) => m.agent === current.agent)
            .map((m, i) => (
              <p key={i} className="text-sm text-slate-200">
                {m.content}
              </p>
            ))}
          {current.agent === 'detection' && result?.detection && (
            <p className="text-xs text-slate-400">
              Pattern: {result.detection.attack_pattern} &middot; Confidence: {result.detection.confidence}%
            </p>
          )}
          {current.agent === 'investigation' && result?.investigation && (
            <p className="text-xs text-slate-400">Objective: {result.investigation.attacker_objective}</p>
          )}
          {current.agent === 'threat_intel' && result?.threat_intel_findings && result.threat_intel_findings.mitre_techniques.length > 0 && (
            <ul className="space-y-1">
              {result.threat_intel_findings.mitre_techniques.map((t) => (
                <li key={t.id} className="text-xs text-slate-400">
                  <span className="font-mono text-slate-300">{t.id}</span> {t.name} &mdash; {t.evidence}
                </li>
              ))}
            </ul>
          )}
          {current.agent === 'risk' && result?.risk && (
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <SeverityBadge severity={result.risk.business_risk_level} />
              Score {result.risk.business_risk_score}/100
              {result.risk.most_critical_asset && ` · Most critical asset: ${result.risk.most_critical_asset}`}
            </div>
          )}
          {current.agent === 'response' && result?.response && (
            <p className="text-xs text-slate-400">
              Urgency: {result.response.urgency} &middot; {result.response.proposed_actions.length} proposed action(s)
            </p>
          )}
        </div>
      )}
    </div>
  )
}
