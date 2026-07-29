import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Login failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <form onSubmit={handleSubmit} className="w-full max-w-sm panel p-8 space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-foreground">SentraOps</h1>
          <p className="text-sm text-muted-foreground">Sign in to the SOC console</p>
        </div>

        {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

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
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg bg-secondary border border-border px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
        </div>

        <button
          disabled={submitting}
          type="submit"
          className="w-full rounded-lg bg-primary hover:bg-primary disabled:opacity-50 text-white font-medium py-2 transition"
        >
          {submitting ? 'Signing in...' : 'Sign in'}
        </button>

        <p className="text-sm text-muted-foreground text-center">
          No account?{' '}
          <Link to="/register" className="text-primary hover:underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  )
}
