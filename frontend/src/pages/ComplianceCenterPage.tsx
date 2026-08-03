import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import type { ComplianceControl, ComplianceReport, ComplianceStatus } from '../api/types'

const STATUS_STYLES: Record<ComplianceStatus, string> = {
  satisfied: 'bg-severity-low/80 text-severity-low',
  partial: 'bg-severity-medium/80 text-severity-medium',
  not_satisfied: 'bg-destructive/80 text-destructive',
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
  const canAct = roleCanAct(user?.role)

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
          <h1 className="text-lg font-semibold text-foreground">Compliance Center</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Controls illustrative of common SOC2, ISO27001, GDPR, NIST CSF, MITRE ATT&CK, CIS, and PCI DSS
            practice, evaluated fresh against this organization's real data - not a certified audit, not a
            static checklist.
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void generateReport()}
            disabled={generating}
            className="rounded-lg bg-primary hover:bg-primary disabled:opacity-50 text-white text-sm font-medium px-4 py-2 transition"
          >
            {generating ? 'Generating...' : 'Generate Compliance Report'}
          </button>
        )}
      </div>

      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      {!loading && (
        <p className="text-sm text-muted-foreground">
          {satisfiedCount} of {controls.length} controls satisfied
        </p>
      )}

      {report && (
        <div className="rounded-xl border border-primary/60 bg-primary/20 p-5 space-y-2">
          <p className="text-sm font-medium text-primary">{report.overall_posture}</p>
          <p className="text-sm text-foreground">{report.summary}</p>
          {report.gaps.length > 0 && (
            <ul className="list-disc list-inside text-sm text-foreground space-y-0.5">
              {report.gaps.map((gap, i) => (
                <li key={i}>{gap}</li>
              ))}
            </ul>
          )}
          <p className="text-xs text-muted-foreground pt-1">Next steps: {report.next_steps}</p>
        </div>
      )}

      {loading && <p className="text-muted-foreground text-sm">Loading...</p>}

      {!loading &&
        Object.entries(byFramework).map(([framework, items]) => (
          <div key={framework} className="panel divide-y divide-secondary">
            <h2 className="text-sm font-medium text-foreground p-4 pb-2">{framework}</h2>
            {items.map((control) => (
              <div key={control.id} className="p-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm text-foreground">
                    <span className="font-mono text-muted-foreground mr-2">{control.control_id}</span>
                    {control.title}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">{control.description}</p>
                  <p className="text-xs text-muted-foreground mt-1.5">{control.evidence}</p>
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
