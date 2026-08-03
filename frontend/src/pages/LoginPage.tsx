import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { AuthLayout } from '../components/AuthLayout'

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
    <AuthLayout>
      <form onSubmit={handleSubmit} className="panel space-y-4 p-8 shadow-2xl shadow-black/20">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Welcome back</h1>
          <p className="text-sm text-muted-foreground">Sign in to your SOC console</p>
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
          className="w-full rounded-lg bg-primary py-2 font-medium text-white transition hover:opacity-90 disabled:opacity-50 glow-primary"
        >
          {submitting ? 'Signing in...' : 'Sign in'}
        </button>

        <p className="text-center text-sm text-muted-foreground">
          No account?{' '}
          <Link to="/register" className="text-primary hover:underline">
            Register
          </Link>
        </p>
      </form>
    </AuthLayout>
  )
}
