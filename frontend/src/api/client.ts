import type {
  AppNotification,
  Asset,
  ChatResponse,
  EventItem,
  IncidentComment,
  IncidentDetail,
  IncidentStatus,
  IncidentSummary,
  Role,
  SearchResults,
  Severity,
  Stats,
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

function buildUrl(path: string, params?: Record<string, string | number | undefined>): URL {
  const url = new URL(`${API_BASE}${path}`, window.location.origin)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== '') url.searchParams.set(key, String(value))
    }
  }
  return url
}

interface RequestOptions {
  method?: string
  body?: unknown
  params?: Record<string, string | number | undefined>
  auth?: boolean
}

async function authedFetch(url: URL, method: string, body?: unknown, auth = true): Promise<Response> {
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
  return res
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, params, auth = true } = options
  const res = await authedFetch(buildUrl(path, params), method, body, auth)

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

async function downloadFile(path: string, params: Record<string, string | number | undefined> | undefined, filename: string): Promise<void> {
  const res = await authedFetch(buildUrl(path, params), 'GET')
  if (!res.ok) throw new ApiError(res.status, res.statusText)

  const blob = await res.blob()
  const objectUrl = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = objectUrl
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(objectUrl)
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
  downloadEventsCsv: (params: { q?: string; event_type?: string; severity?: string }) =>
    downloadFile('/events/export.csv', params, 'events.csv'),

  simulate: (scenario: string) => request<unknown>(`/simulate/${scenario}`, { method: 'POST' }),
  correlate: () => request<{ incidents_created: number }>('/correlate', { method: 'POST' }),

  listIncidents: (params: { status?: string; risk_level?: string; limit?: number; offset?: number }) =>
    request<{ total: number; incidents: IncidentSummary[] }>('/incidents', { params }),
  downloadIncidentsCsv: (params: { status?: string; risk_level?: string }) =>
    downloadFile('/incidents/export.csv', params, 'incidents.csv'),
  getIncident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  downloadIncidentReport: (id: number) => downloadFile(`/incidents/${id}/report.md`, undefined, `incident-${id}-report.md`),
  updateIncident: (id: number, payload: { status?: IncidentStatus; priority?: Severity; assignee_id?: number | null }) =>
    request<IncidentDetail>(`/incidents/${id}`, { method: 'PATCH', body: payload }),
  addComment: (id: number, body: string) => request<IncidentComment>(`/incidents/${id}/comments`, { method: 'POST', body: { body } }),

  listAssets: (params: { q?: string; limit?: number; offset?: number }) =>
    request<{ total: number; assets: Asset[] }>('/assets', { params }),
  updateAsset: (id: number, payload: { os?: string; department?: string; owner?: string; criticality?: Severity }) =>
    request<Asset>(`/assets/${id}`, { method: 'PATCH', body: payload }),

  search: (q: string) => request<SearchResults>('/search', { params: { q } }),

  getStats: () => request<Stats>('/stats'),

  chat: (question: string) => request<ChatResponse>('/chat', { method: 'POST', body: { question } }),

  listNotifications: (params: { unread_only?: boolean } = {}) =>
    request<{ unread_count: number; notifications: AppNotification[] }>('/notifications', {
      params: { unread_only: params.unread_only ? 'true' : undefined },
    }),
  markNotificationRead: (id: number) => request<AppNotification>(`/notifications/${id}/read`, { method: 'PATCH' }),
  markAllNotificationsRead: () => request<{ status: string }>('/notifications/read-all', { method: 'POST' }),
}
