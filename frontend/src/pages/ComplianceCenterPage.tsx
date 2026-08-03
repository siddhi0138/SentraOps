import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import type { ComplianceControl, ComplianceReport, ComplianceStatus } from '../api/types'

const STATUS_STYLES: Record<ComplianceStatus, string> = {
  satisfied: 'bg-emerald-700/80 text-emerald-50',
  partial: 'bg-amber-600/80 text-amber-50',
  not_satisfied: 'bg-red-800/80 text-red-50',
}

const STATUS_LABELS: Record<ComplianceStatus, string> = {
  satisfied: 'Satisfied',
  partial: 'Partial',
  not_satisfied: 'Not Satisfied',
}

function StatusBadge({ status }: { status: ComplianceStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide ${STATUS_STYLES[status]}`}>
      {STATUS_LABELS[status]}
    </span>
  )
}

export function ComplianceCenterPage() {
  const { user } = useAuth()
  const canAct = user?.role === 'admin' || user?.role === 'analyst'

  const [controls, setControls] = useState<ComplianceControl[]>([])
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.listComplianceControls()
      setControls(res.controls)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load compliance controls')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function generateReport() {
    setGenerating(true)
    setError(null)
    try {
      const res = await api.getComplianceReport()
      setReport(res.report)
      setControls(res.controls)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate report')
    } finally {
      setGenerating(false)
    }
  }

  const byFramework = controls.reduce<Record<string, ComplianceControl[]>>((acc, c) => {
    ;(acc[c.framework] ??= []).push(c)
    return acc
  }, {})

  const satisfiedCount = controls.filter((c) => c.status === 'satisfied').length

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Compliance Center</h1>
          <p className="text-sm text-slate-500 mt-1">
            Controls illustrative of common SOC2, ISO27001, GDPR, NIST CSF, MITRE ATT&CK, CIS, and PCI DSS
            practice, evaluated fresh against this organization's real data - not a certified audit, not a
            static checklist.
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void generateReport()}
            disabled={generating}
            className="rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 transition"
          >
            {generating ? 'Generating...' : 'Generate Compliance Report'}
          </button>
        )}
      </div>

      {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

      {!loading && (
        <p className="text-sm text-slate-400">
          {satisfiedCount} of {controls.length} controls satisfied
        </p>
      )}

      {report && (
        <div className="rounded-xl border border-indigo-900/60 bg-indigo-950/20 p-5 space-y-2">
          <p className="text-sm font-medium text-indigo-300">{report.overall_posture}</p>
          <p className="text-sm text-slate-300">{report.summary}</p>
          {report.gaps.length > 0 && (
            <ul className="list-disc list-inside text-sm text-slate-300 space-y-0.5">
              {report.gaps.map((gap, i) => (
                <li key={i}>{gap}</li>
              ))}
            </ul>
          )}
          <p className="text-xs text-slate-500 pt-1">Next steps: {report.next_steps}</p>
        </div>
      )}

      {loading && <p className="text-slate-400 text-sm">Loading...</p>}

      {!loading &&
        Object.entries(byFramework).map(([framework, items]) => (
          <div key={framework} className="rounded-xl border border-slate-800 bg-slate-900/60 divide-y divide-slate-800">
            <h2 className="text-sm font-medium text-slate-300 p-4 pb-2">{framework}</h2>
            {items.map((control) => (
              <div key={control.id} className="p-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm text-slate-100">
                    <span className="font-mono text-slate-500 mr-2">{control.control_id}</span>
                    {control.title}
                  </p>
                  <p className="text-xs text-slate-500 mt-1">{control.description}</p>
                  <p className="text-xs text-slate-400 mt-1.5">{control.evidence}</p>
                </div>
                <div className="shrink-0">
                  <StatusBadge status={control.status} />
                </div>
              </div>
            ))}
          </div>
        ))}
    </div>
  )
}
