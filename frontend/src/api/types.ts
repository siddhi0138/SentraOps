export type Role = 'admin' | 'analyst' | 'viewer'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'open' | 'closed'

export interface User {
  id: number
  email: string
  role: Role
  is_active: boolean
}

export interface TokenPair {
  access_token: string
  refresh_token: string
  token_type: string
}

export interface EventItem {
  id: number
  timestamp: string
  host: string
  username: string | null
  source_ip: string | null
  event_type: string
  severity: Severity
  message: string
  source_type: string
  incident_id: number | null
}

export interface ThreatIntelMatch {
  indicator: string
  indicator_type: string
  verdict: string
  confidence: number
  source: string
}

export interface IncidentSummary {
  id: number
  title: string
  confidence: number
  risk_score: number
  risk_level: Severity
  status: IncidentStatus
  priority: Severity
  assignee_id: number | null
  assignee_email: string | null
  affected_hosts: string[]
  affected_users: string[]
  event_count: number
  created_at: string
}

export interface IncidentComment {
  id: number
  incident_id: number
  author_email: string | null
  body: string
  created_at: string
}

export interface IncidentDetail extends IncidentSummary {
  risk_factors: string[]
  threat_intel: ThreatIntelMatch[]
  recommended_actions: string[]
  report: string
  timeline: EventItem[]
  comments: IncidentComment[]
}

export interface Asset {
  id: number
  host: string
  first_seen: string
  last_seen: string
  event_count: number
  os: string | null
  department: string | null
  owner: string | null
  criticality: Severity
}

export interface SearchResults {
  events: EventItem[]
  incidents: IncidentSummary[]
  assets: Asset[]
}

export interface AppNotification {
  id: number
  message: string
  incident_id: number | null
  is_read: boolean
  created_at: string
}

export interface Stats {
  total_events: number
  total_incidents: number
  open_incidents: number
  critical_incidents: number
  severity_distribution: Record<Severity, number>
  recent_incidents: IncidentSummary[]
}

export interface RagResult {
  content_type: 'event' | 'incident'
  content_id: number | null
  text: string
  score: number | null
}

export interface ChatResponse {
  question: string
  answer: string
  sources: RagResult[]
}

export interface IncidentExplanation {
  explanation: string
  timeline_narrative: string
  attack_type: string
  affected_user: string
  affected_assets: string
  impact: string
  confidence: number
}
