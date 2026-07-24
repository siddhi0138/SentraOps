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
  affected_hosts: string[]
  affected_users: string[]
  event_count: number
  created_at: string
}

export interface IncidentDetail extends IncidentSummary {
  risk_factors: string[]
  threat_intel: ThreatIntelMatch[]
  recommended_actions: string[]
  report: string
  timeline: EventItem[]
}
