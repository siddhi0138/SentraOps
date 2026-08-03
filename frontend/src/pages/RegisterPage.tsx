import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'

type Mode = 'create' | 'join'

export function RegisterPage() {
  const { register, createOrganization } = useAuth()
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('create')
  const [organizationName, setOrganizationName] = useState('')
  const [organizationSlug, setOrganizationSlug] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      if (mode === 'create') {
        await createOrganization(organizationName, email, password)
      } else {
        await register(email, password, organizationSlug)
      }
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Registration failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4">
      <form onSubmit={handleSubmit} className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">
            {mode === 'create' ? 'Set up your organization' : 'Join an organization'}
          </h1>
          <p className="text-sm text-slate-400">
            {mode === 'create'
              ? "You'll be the first admin of a brand new CyberSentinel workspace."
              : 'Ask an admin for your organization\'s invite code.'}
          </p>
        </div>

        <div className="flex rounded-lg border border-slate-800 overflow-hidden text-sm">
          <button
            type="button"
            onClick={() => setMode('create')}
            className={`flex-1 py-1.5 transition ${mode === 'create' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'}`}
          >
            New organization
          </button>
          <button
            type="button"
            onClick={() => setMode('join')}
            className={`flex-1 py-1.5 transition ${mode === 'join' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:bg-slate-800'}`}
          >
            Join existing
          </button>
        </div>

        {error && <p className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded-lg px-3 py-2">{error}</p>}

        {mode === 'create' ? (
          <div className="space-y-1">
            <label className="text-xs uppercase tracking-wide text-slate-400">Organization name</label>
            <input
              required
              value={organizationName}
              onChange={(e) => setOrganizationName(e.target.value)}
              placeholder="Acme Corp"
              className="w-full rounded-lg bg-slate-800 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        ) : (
          <div className="space-y-1">
            <label className="text-xs uppercase tracking-wide text-slate-400">Invite code</label>
            <input
              required
              value={organizationSlug}
              onChange={(e) => setOrganizationSlug(e.target.value)}
              placeholder="acme-corp"
              className="w-full rounded-lg bg-slate-800 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        )}

        <div className="space-y-1">
          <label className="text-xs uppercase tracking-wide text-slate-400">Email</label>
          <input
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg bg-slate-800 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs uppercase tracking-wide text-slate-400">Password</label>
          <input
            required
            minLength={8}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg bg-slate-800 border border-slate-700 px-3 py-2 text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>

        <button
          disabled={submitting}
          type="submit"
          className="w-full rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium py-2 transition"
        >
          {submitting ? 'Creating account...' : mode === 'create' ? 'Create organization' : 'Join organization'}
        </button>

        <p className="text-sm text-slate-400 text-center">
          Already have an account?{' '}
          <Link to="/login" className="text-indigo-400 hover:underline">
            Sign in
          </Link>
        </p>
      </form>
    </div>
  )
}
