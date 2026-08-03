import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AuthLayout } from '../components/AuthLayout'

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
    <AuthLayout>
      <form onSubmit={handleSubmit} className="panel space-y-4 p-8 shadow-2xl shadow-black/20">
        <div>
          <h1 className="text-xl font-semibold text-foreground">
            {mode === 'create' ? 'Set up your organization' : 'Join an organization'}
          </h1>
          <p className="text-sm text-muted-foreground">
            {mode === 'create'
              ? "You'll be the first admin of a brand new SentraOps workspace."
              : 'Ask an admin for your organization\'s invite code.'}
          </p>
        </div>

        <div className="flex rounded-lg border border-secondary overflow-hidden text-sm">
          <button
            type="button"
            onClick={() => setMode('create')}
            className={`flex-1 py-1.5 transition ${mode === 'create' ? 'bg-primary text-white' : 'text-muted-foreground hover:bg-secondary'}`}
          >
            New organization
          </button>
          <button
            type="button"
            onClick={() => setMode('join')}
            className={`flex-1 py-1.5 transition ${mode === 'join' ? 'bg-primary text-white' : 'text-muted-foreground hover:bg-secondary'}`}
          >
            Join existing
          </button>
        </div>

        {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

        {mode === 'create' ? (
          <div className="space-y-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">Organization name</label>
            <input
              required
              value={organizationName}
              onChange={(e) => setOrganizationName(e.target.value)}
              placeholder="Acme Corp"
              className="w-full rounded-lg bg-secondary border border-border px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        ) : (
          <div className="space-y-1">
            <label className="text-xs uppercase tracking-wide text-muted-foreground">Invite code</label>
            <input
              required
              value={organizationSlug}
              onChange={(e) => setOrganizationSlug(e.target.value)}
              placeholder="acme-corp"
              className="w-full rounded-lg bg-secondary border border-border px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        )}

        <div className="space-y-1">
          <label className="text-xs uppercase tracking-wide text-muted-foreground">Email</label>
          <input
            required
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg bg-secondary border border-border px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs uppercase tracking-wide text-muted-foreground">Password</label>
          <input
            required
            minLength={8}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg bg-secondary border border-border px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        <button
          disabled={submitting}
          type="submit"
          className="w-full rounded-lg bg-primary py-2 font-medium text-white transition hover:opacity-90 disabled:opacity-50 glow-primary"
        >
          {submitting ? 'Creating account...' : mode === 'create' ? 'Create organization' : 'Join organization'}
        </button>

        <p className="text-center text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link to="/login" className="text-primary hover:underline">
            Sign in
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
