import type {
  AgentInvestigationResult,
  AgentRunDetail,
  AgentRunListItem,
  AgentRunStatus,
  AgentRunSummary,
  AiObservabilitySummary,
  AppNotification,
  Asset,
  ChatResponse,
  ConnectorInstance,
  ConnectorPluginType,
  EventExplanation,
  EventItem,
  GraphData,
  IncidentComment,
  IncidentDetail,
  IncidentExplanation,
  IncidentMemory,
  IncidentStatus,
  IncidentSummary,
  ProposedAction,
  ProposedActionReviewStatus,
  QueryResult,
  AnalystFeedback,
  ApiKeyCreated,
  ApiKeySummary,
  AuditLogEntryItem,
  CommandCenterQueue,
  ComplianceControl,
  ComplianceReportResponse,
  DigitalTwinNarrativeResponse,
  DigitalTwinSimulation,
  EvaluationSummary,
  ExecutiveBriefingResponse,
  ExecutiveSummary,
  FeedbackRating,
  LearningStats,
  Playbook,
  OrganizationSettings,
  PredictiveBriefingResponse,
  PredictiveSummary,
  ResponseActionInstance,
  ResponseActionPluginType,
  ShiftNote,
  StreamingStatus,
  ThreatIndicator,
  ThreatIndicatorType,
  SimilarIncident,
  Role,
  SearchResults,
  Severity,
  Stats,
  TokenPair,
  User,
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api'
const ACCESS_KEY = 'sentraops_access_token'
const REFRESH_KEY = 'sentraops_refresh_token'

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

// A plain browser navigation (<a href>), not a fetch() - GET
// /connectors/slack/authorize needs the JWT as a query param instead of an
// Authorization header, since a full-page redirect can't set custom
// headers. See backend/app/main.py's slack_authorize docstring.
export function slackAuthorizeUrl(): string {
  return `${API_BASE}/connectors/slack/authorize?token=${encodeURIComponent(getAccessToken() ?? '')}`
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

function buildWsUrl(path: string, params?: Record<string, string | undefined>): string {
  const url = buildUrl(path)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) url.searchParams.set(key, value)
    }
  }
  return url.toString()
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
  register: (email: string, password: string, organization_slug: string) =>
    request<User>('/auth/register', { method: 'POST', body: { email, password, organization_slug }, auth: false }),
  createOrganization: (organization_name: string, email: string, password: string) =>
    request<User>('/organizations', { method: 'POST', body: { organization_name, email, password }, auth: false }),
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
  explainEvent: (id: number) => request<EventExplanation>(`/events/${id}/explain`),
  naturalLanguageQuery: (question: string) => request<QueryResult>('/query', { method: 'POST', body: { question } }),

  simulate: (scenario: string) => request<unknown>(`/simulate/${scenario}`, { method: 'POST' }),
  correlate: () => request<{ incidents_created: number; incidents: IncidentSummary[] }>('/correlate', { method: 'POST' }),

  listIncidents: (params: { status?: string; risk_level?: string; limit?: number; offset?: number }) =>
    request<{ total: number; incidents: IncidentSummary[] }>('/incidents', { params }),
  downloadIncidentsCsv: (params: { status?: string; risk_level?: string }) =>
    downloadFile('/incidents/export.csv', params, 'incidents.csv'),
  getIncident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  downloadIncidentReport: (id: number) => downloadFile(`/incidents/${id}/report.md`, undefined, `incident-${id}-report.md`),
  explainIncident: (id: number, audience: 'analyst' | 'executive' = 'analyst') =>
    request<IncidentExplanation>(`/incidents/${id}/explain`, { params: { audience } }),
  similarIncidents: (id: number) => request<{ incident_id: number; matches: SimilarIncident[] }>(`/incidents/${id}/similar`),
  updateIncident: (id: number, payload: { status?: IncidentStatus; priority?: Severity; assignee_id?: number | null }) =>
    request<IncidentDetail>(`/incidents/${id}`, { method: 'PATCH', body: payload }),
  addComment: (id: number, body: string) => request<IncidentComment>(`/incidents/${id}/comments`, { method: 'POST', body: { body } }),

  getIncidentMemory: (id: number) => request<IncidentMemory>(`/incidents/${id}/memory`),
  investigateIncident: (id: number) => request<AgentInvestigationResult>(`/incidents/${id}/investigate`, { method: 'POST' }),
  investigateIncidentLive: (id: number) =>
    request<{ run_id: number; incident_id: number; status: AgentRunStatus }>(`/incidents/${id}/investigate-live`, {
      method: 'POST',
    }),
  agentRunWsUrl: (runId: number) => buildWsUrl(`/ws/agent-runs/${runId}`, { token: getAccessToken() ?? '' }),
  listAgentRuns: (id: number) => request<{ incident_id: number; runs: AgentRunSummary[] }>(`/incidents/${id}/agent-runs`),
  listAllAgentRuns: (params: { status?: AgentRunStatus; limit?: number } = {}) =>
    request<{ runs: AgentRunListItem[] }>('/agent-runs', { params }),
  getAgentRun: (runId: number) => request<AgentRunDetail>(`/agent-runs/${runId}`),

  syncGraph: () => request<{ incidents: number; events_processed: number }>('/graph/sync', { method: 'POST' }),
  getIncidentGraph: (id: number) => request<GraphData>(`/graph/incident/${id}`),
  getEntityBlastRadius: (type: 'host' | 'user' | 'ip', value: string, hops = 2) =>
    request<GraphData>('/graph/entity', { params: { type, value, hops } }),
  getFullGraph: (limit = 300) => request<GraphData>('/graph', { params: { limit } }),
  simulateCompromise: (type: 'host' | 'user' | 'ip', value: string, hops = 2) =>
    request<DigitalTwinSimulation>('/digital-twin/simulate', { params: { type, value, hops } }),
  getDigitalTwinNarrative: (type: 'host' | 'user' | 'ip', value: string, hops = 2) =>
    request<DigitalTwinNarrativeResponse>('/digital-twin/narrative', { method: 'POST', params: { type, value, hops } }),
  getAiObservabilitySummary: () => request<AiObservabilitySummary>('/observability/ai-summary'),

  getThreatIntelGraph: (limit = 300) => request<GraphData>('/threat-intel/graph', { params: { limit } }),
  syncThreatIntelGraph: () =>
    request<{ indicators: number; tag_links: number; incident_matches: number }>('/threat-intel/graph/sync', {
      method: 'POST',
    }),
  listProposedActions: (id: number) =>
    request<{ incident_id: number; actions: ProposedAction[] }>(`/incidents/${id}/proposed-actions`),
  reviewProposedAction: (actionId: number, status: ProposedActionReviewStatus) =>
    request<ProposedAction>(`/proposed-actions/${actionId}`, { method: 'PATCH', body: { status } }),
  executeProposedAction: (actionId: number) =>
    request<ProposedAction>(`/proposed-actions/${actionId}/execute`, { method: 'POST' }),

  listConnectorPlugins: () => request<{ connectors: ConnectorPluginType[] }>('/plugins/connectors'),
  listResponseActionPlugins: () => request<{ actions: ResponseActionPluginType[] }>('/plugins/response-actions'),
  listConnectors: () => request<{ connectors: ConnectorInstance[] }>('/connectors'),
  createConnector: (payload: { plugin_key: string; name: string; config: Record<string, string> }) =>
    request<ConnectorInstance>('/connectors', { method: 'POST', body: payload }),
  testConnector: (id: number) => request<{ ok: boolean; message: string }>(`/connectors/${id}/test`, { method: 'POST' }),
  syncConnector: (id: number) =>
    request<{ connector: ConnectorInstance; ingested: number; skipped: number }>(`/connectors/${id}/sync`, {
      method: 'POST',
    }),
  updateConnectorConfig: (id: number, config: Record<string, string>) =>
    request<ConnectorInstance>(`/connectors/${id}`, { method: 'PATCH', body: { config } }),
  listResponseActionInstances: () =>
    request<{ actions: ResponseActionInstance[] }>('/response-action-instances'),
  createResponseActionInstance: (payload: { plugin_key: string; name: string; config: Record<string, string> }) =>
    request<ResponseActionInstance>('/response-action-instances', { method: 'POST', body: payload }),

  getCurrentOrganization: () => request<OrganizationSettings>('/organizations/current'),
  renameOrganization: (name: string) =>
    request<OrganizationSettings>('/organizations/current', { method: 'PATCH', body: { name } }),
  rotateInviteCode: () => request<OrganizationSettings>('/organizations/current/rotate-invite-code', { method: 'POST' }),
  listApiKeys: () => request<{ api_keys: ApiKeySummary[] }>('/api-keys'),
  createApiKey: (name: string, userId?: number) =>
    request<ApiKeyCreated>('/api-keys', { method: 'POST', body: { name, user_id: userId } }),
  revokeApiKey: (id: number) => request<ApiKeySummary>(`/api-keys/${id}/revoke`, { method: 'POST' }),
  listAuditLog: (limit = 50) => request<{ entries: AuditLogEntryItem[] }>('/audit-log', { params: { limit } }),

  listMarketplacePlaybooks: () => request<{ playbooks: Playbook[] }>('/marketplace/playbooks'),
  installPlaybook: (id: number) => request<Playbook>(`/marketplace/playbooks/${id}/install`, { method: 'POST' }),
  uninstallPlaybook: (id: number) => request<Playbook>(`/marketplace/playbooks/${id}/uninstall`, { method: 'POST' }),

  getCommandCenterQueue: () => request<CommandCenterQueue>('/command-center/queue'),
  listShiftNotes: (limit = 20) => request<{ notes: ShiftNote[] }>('/shift-notes', { params: { limit } }),
  createShiftNote: (body: string) => request<ShiftNote>('/shift-notes', { method: 'POST', body: { body } }),

  submitIncidentFeedback: (incidentId: number, payload: { rating: FeedbackRating; note?: string; agent_run_id?: number }) =>
    request<AnalystFeedback>(`/incidents/${incidentId}/feedback`, { method: 'POST', body: payload }),
  listIncidentFeedback: (incidentId: number) =>
    request<{ incident_id: number; feedback: AnalystFeedback[] }>(`/incidents/${incidentId}/feedback`),
  getLearningStats: () => request<LearningStats>('/learning/stats'),
  getEvaluationSummary: () => request<EvaluationSummary>('/learning/evaluation'),

  listComplianceControls: () => request<{ controls: ComplianceControl[] }>('/compliance/controls'),
  getComplianceReport: () => request<ComplianceReportResponse>('/compliance/report', { method: 'POST' }),

  getExecutiveSummary: () => request<ExecutiveSummary>('/executive/summary'),
  getExecutiveBriefing: () => request<ExecutiveBriefingResponse>('/executive/briefing', { method: 'POST' }),

  getPredictiveSummary: () => request<PredictiveSummary>('/predictive/summary'),
  getPredictiveBriefing: () => request<PredictiveBriefingResponse>('/predictive/briefing', { method: 'POST' }),

  listThreatIndicators: (params: { q?: string; indicator_type?: ThreatIndicatorType; limit?: number } = {}) =>
    request<{ indicators: ThreatIndicator[] }>('/threat-intel/indicators', { params }),
  syncThreatIntel: () => request<{ synced: number }>('/threat-intel/sync', { method: 'POST' }),

  getStreamingStatus: () => request<StreamingStatus>('/streaming/status'),
  sendTestStreamLog: () =>
    request<{ queued: number }>('/ingest/generic/stream', {
      method: 'POST',
      body: {
        logs: [
          {
            host: 'stream-test-host',
            event_type: 'streaming_test_event',
            severity: 'low',
            message: `Test log sent via streaming ingestion at ${new Date().toISOString()}`,
          },
        ],
      },
    }),

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
