import type {
  EventItem,
  IncidentDetail,
  IncidentStatus,
  IncidentSummary,
  Role,
  TokenPair,
  User,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api'
const ACCESS_KEY = 'cybersentinel_access_token'
const REFRESH_KEY = 'cybersentinel_refresh_token'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY)
}

function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY)
}

export function setTokens(pair: TokenPair): void {
  localStorage.setItem(ACCESS_KEY, pair.access_token)
  localStorage.setItem(REFRESH_KEY, pair.refresh_token)
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
}

async function refreshAccessToken(): Promise<boolean> {
  const refresh_token = getRefreshToken()
  if (!refresh_token) return false

  const res = await fetch(`${API_BASE}/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token }),
  })
  if (!res.ok) return false

  setTokens(await res.json())
  return true
}

interface RequestOptions {
  method?: string
  body?: unknown
  params?: Record<string, string | number | undefined>
  auth?: boolean
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, params, auth = true } = options

  const url = new URL(`${API_BASE}${path}`, window.location.origin)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') url.searchParams.set(key, String(value))
    }
  }

  const doFetch = () => {
    const headers: Record<string, string> = {}
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (auth) {
      const token = getAccessToken()
      if (token) headers.Authorization = `Bearer ${token}`
    }
    return fetch(url.toString(), {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  }

  let res = await doFetch()

  if (res.status === 401 && auth && (await refreshAccessToken())) {
    res = await doFetch()
  }

  if (!res.ok) {
    let detail = res.statusText
    try {
      const data = await res.json()
      detail = data.detail ?? detail
    } catch {
      /* body wasn't JSON; fall back to statusText */
    }
    throw new ApiError(res.status, detail)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export const api = {
  register: (email: string, password: string) =>
    request<User>('/auth/register', { method: 'POST', body: { email, password }, auth: false }),
  login: (email: string, password: string) =>
    request<TokenPair>('/auth/login', { method: 'POST', body: { email, password }, auth: false }),
  me: () => request<User>('/auth/me'),

  listUsers: () => request<User[]>('/users'),
  updateUserRole: (id: number, role: Role) => request<User>(`/users/${id}/role`, { method: 'PATCH', body: { role } }),

  listEvents: (params: {
    q?: string
    event_type?: string
    severity?: string
    username?: string
    host?: string
    source_ip?: string
    limit?: number
    offset?: number
  }) => request<{ total: number; events: EventItem[] }>('/events', { params }),

  simulate: (scenario: string) => request<unknown>(`/simulate/${scenario}`, { method: 'POST' }),
  correlate: () => request<{ incidents_created: number }>('/correlate', { method: 'POST' }),

  listIncidents: (params: { status?: string; risk_level?: string; limit?: number; offset?: number }) =>
    request<{ total: number; incidents: IncidentSummary[] }>('/incidents', { params }),
  getIncident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  updateIncidentStatus: (id: number, status: IncidentStatus) =>
    request<IncidentDetail>(`/incidents/${id}`, { method: 'PATCH', params: { status } }),
}
