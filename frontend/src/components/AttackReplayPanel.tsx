import { useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { usePersistentState } from '../hooks/usePersistentState'
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
  // Which run is selected and how far the user has scrubbed both survive a
  // refresh (keyed per incident) - previously both silently reset (back to
  // the latest run, step 1) on every reload, discarding exactly where the
  // user had gotten to.
  const [selectedRun, setSelectedRun] = usePersistentState<AgentRunDetail>(`attack-replay-run-${incidentId}`)
  const [persistedIndex, setPersistedIndex] = usePersistentState<number>(`attack-replay-index-${incidentId}`, 0)
  const index = persistedIndex ?? 0
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [playing, setPlaying] = useState(false)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  function setIndex(update: number | ((prev: number) => number)) {
    setPersistedIndex((prev) => (typeof update === 'function' ? (update as (p: number) => number)(prev ?? 0) : update))
  }

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      try {
        const { runs: list } = await api.listAgentRuns(incidentId)
        if (cancelled) return
        setRuns(list)
        // Only auto-pick the latest run the first time this incident is
        // viewed in this session - if a run is already persisted (a real
        // refresh, not a fresh visit), keep showing exactly what the user
        // had selected instead of silently jumping back to the newest one.
        if (!selectedRun) {
          const latestCompleted = [...list].reverse().find((r) => r.status === 'completed') ?? list[list.length - 1]
          if (latestCompleted) {
            setSelectedRun(await api.getAgentRun(latestCompleted.id))
          }
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
    // Clamp rather than always zeroing - a genuinely shorter step list (a
    // different, shorter run selected) still resets out-of-range index to
    // 0, but the initial 0 -> N transition while data loads on a refresh
    // (restoring a persisted index) must not stomp the position the user
    // had just scrubbed to.
    setIndex((i) => (i >= steps.length ? 0 : i))
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

  if (loading) return <p className="text-sm text-muted-foreground">Loading replay...</p>
  if (error) return <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>
  if (steps.length === 0) {
    return <p className="text-sm text-muted-foreground">Nothing to replay yet - ingest events and run an investigation first.</p>
  }

  const current = steps[index]
  const result = selectedRun?.result

  return (
    <div className="rounded-xl border border-severity-medium/50 bg-severity-medium/10 p-5 space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-medium text-severity-medium">Attack Replay</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Real recorded history, step by step - {timeline.length} real event{timeline.length === 1 ? '' : 's'}
            {selectedRun ? `, then the real AI investigation (run #${selectedRun.id})` : ''}.
          </p>
        </div>
        {runs.length > 1 && (
          <select
            value={selectedRun?.id ?? ''}
            onChange={(e) => void selectRun(Number(e.target.value))}
            className="text-xs rounded-lg border border-border bg-card px-2 py-1.5 text-foreground"
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
          className="rounded-lg border border-border hover:bg-secondary disabled:opacity-30 text-xs px-3 py-1.5 transition"
        >
          &larr; Back
        </button>
        <button
          onClick={() => setPlaying((p) => !p)}
          className="rounded-lg bg-severity-medium hover:bg-severity-medium text-white text-xs font-medium px-4 py-1.5 transition"
        >
          {playing ? 'Pause' : index >= steps.length - 1 ? 'Replay' : 'Play'}
        </button>
        <button
          onClick={() => setIndex((i) => (i >= steps.length - 1 ? 0 : i + 1))}
          disabled={index >= steps.length - 1}
          className="rounded-lg border border-border hover:bg-secondary disabled:opacity-30 text-xs px-3 py-1.5 transition"
        >
          Forward &rarr;
        </button>
        <div className="flex-1 h-1.5 rounded-full bg-secondary overflow-hidden">
          <div
            className="h-full bg-severity-medium transition-all"
            style={{ width: `${((index + 1) / steps.length) * 100}%` }}
          />
        </div>
        <span className="text-xs text-muted-foreground shrink-0">
          {index + 1} / {steps.length}
        </span>
      </div>

      {current.kind === 'event' ? (
        <div className="panel p-4">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs uppercase tracking-wide text-muted-foreground">Real Event</span>
            <SeverityBadge severity={current.event.severity} />
          </div>
          <p className="text-sm text-foreground">{current.event.message}</p>
          <p className="text-xs text-muted-foreground mt-2">
            {current.event.timestamp} &middot; {current.event.host}
            {current.event.username && ` · ${current.event.username}`}
            {current.event.source_ip && ` · ${current.event.source_ip}`} &middot; {current.event.event_type}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-agent/60 bg-agent/10 p-4 space-y-2">
          <span className="text-xs uppercase tracking-wide text-agent">{AGENT_LABELS[current.agent]}</span>
          {selectedRun?.messages
            .filter((m) => m.agent === current.agent)
            .map((m, i) => (
              <p key={i} className="text-sm text-foreground">
                {m.content}
              </p>
            ))}
          {current.agent === 'detection' && result?.detection && (
            <p className="text-xs text-muted-foreground">
              Pattern: {result.detection.attack_pattern} &middot; Confidence: {result.detection.confidence}%
            </p>
          )}
          {current.agent === 'investigation' && result?.investigation && (
            <p className="text-xs text-muted-foreground">Objective: {result.investigation.attacker_objective}</p>
          )}
          {current.agent === 'threat_intel' && result?.threat_intel_findings && result.threat_intel_findings.mitre_techniques.length > 0 && (
            <ul className="space-y-1">
              {result.threat_intel_findings.mitre_techniques.map((t) => (
                <li key={t.id} className="text-xs text-muted-foreground">
                  <span className="font-mono text-foreground">{t.id}</span> {t.name} &mdash; {t.evidence}
                </li>
              ))}
            </ul>
          )}
          {current.agent === 'risk' && result?.risk && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <SeverityBadge severity={result.risk.business_risk_level} />
              Score {result.risk.business_risk_score}/100
              {result.risk.most_critical_asset && ` · Most critical asset: ${result.risk.most_critical_asset}`}
            </div>
          )}
          {current.agent === 'response' && result?.response && (
            <p className="text-xs text-muted-foreground">
              Urgency: {result.response.urgency} &middot; {result.response.proposed_actions.length} proposed action(s)
            </p>
          )}
        </div>
      )}
    </div>
  )
}
