import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api, clearTokens, getAccessToken, setTokens } from '../api/client'
import type { User } from '../api/types'

interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, organizationSlug: string) => Promise<void>
  createOrganization: (organizationName: string, email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function restoreSession() {
      if (getAccessToken()) {
        try {
          setUser(await api.me())
        } catch {
          clearTokens()
        }
      }
      setLoading(false)
    }
    void restoreSession()
  }, [])

  async function login(email: string, password: string) {
    setTokens(await api.login(email, password))
    setUser(await api.me())
  }

  async function register(email: string, password: string, organizationSlug: string) {
    await api.register(email, password, organizationSlug)
    await login(email, password)
  }

  async function createOrganization(organizationName: string, email: string, password: string) {
    await api.createOrganization(organizationName, email, password)
    await login(email, password)
  }

  function logout() {
    clearTokens()
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, createOrganization, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
