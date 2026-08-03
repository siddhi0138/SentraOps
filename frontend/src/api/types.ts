export type Role = 'admin' | 'analyst' | 'viewer'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'open' | 'closed'

export interface User {
  id: number
  email: string
  role: Role
  is_active: boolean
  organization_id: number
  organization_name: string
  organization_slug: string
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
  confidence: 'low' | 'medium' | 'high'
  semantic_score: number
  structural_corroboration: number
  evidence_checked: number
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

export interface SimilarIncident extends IncidentSummary {
  similarity: number | null
}

export interface EventExplanation {
  explanation: string
  is_suspicious: boolean
  recommended_action: string
}

export interface QueryFilters {
  event_type: string | null
  severity: Severity | null
  username: string | null
  host: string | null
  source_ip: string | null
  q: string | null
}

export interface QueryResult {
  question: string
  filters: QueryFilters
  total: number
  events: EventItem[]
}

export interface AgentMessage {
  id?: number
  run_id?: number
  agent: string
  content: string
  created_at: string
}

export interface AgentDetection {
  assessment: string
  attack_pattern: string
  confidence: number
  key_indicators: string[]
  related_event_count: number
}

export interface AgentInvestigation {
  timeline_narrative: string
  key_findings: string[]
  attacker_objective: string
}

export interface MitreTechnique {
  id: string
  name: string
  evidence: string
}

export interface AgentThreatIntel {
  summary: string
  mitre_techniques: MitreTechnique[]
  malware_association: string | null
  matches: ThreatIntelMatch[]
  confidence: number
}

export interface AgentRisk {
  business_risk_score: number
  business_risk_level: Severity
  explanation: string
  most_critical_asset: string | null
}

export type ProposedActionCategory = 'containment' | 'eradication' | 'recovery'
export type ProposedActionReviewStatus = 'approved' | 'rejected'
export type ProposedActionStatus = 'pending' | ProposedActionReviewStatus | 'executed' | 'execution_failed'

export interface ActionExecutionResult {
  integration: string
  ok: boolean
  message: string
}

export interface ProposedAction {
  id: number
  incident_id: number
  agent_run_id: number | null
  category: ProposedActionCategory
  description: string
  status: ProposedActionStatus
  reviewed_by_email: string | null
  reviewed_at: string | null
  created_at: string
  executed_at: string | null
  execution_result: ActionExecutionResult[] | null
}

export interface AgentResponse {
  proposed_actions: ProposedAction[]
  urgency: 'low' | 'medium' | 'high' | 'immediate'
  requires_approval: boolean
}

export interface AgentReport {
  executive_summary: string
  technical_summary: string
  compliance_notes: string
  customer_notification: string
}

export interface AgentRunResult {
  detection?: AgentDetection
  investigation?: AgentInvestigation
  threat_intel_findings?: AgentThreatIntel
  risk?: AgentRisk
  response?: AgentResponse
  report?: AgentReport
  stage?: string
}

export type AgentRunStatus = 'running' | 'completed' | 'failed'

export interface AgentRunSummary {
  id: number
  incident_id: number
  status: AgentRunStatus
  triggered_by_email: string | null
  started_at: string
  completed_at: string | null
  stage: string | null
}

export interface AgentRunDetail extends AgentRunSummary {
  error: string | null
  result: AgentRunResult | null
  messages: AgentMessage[]
}

export interface AgentInvestigationResult extends AgentRunResult {
  run_id: number
  incident_id: number
  messages: AgentMessage[]
}

export interface MemorySimilarIncident {
  incident_id: number
  title: string
  risk_level: Severity
  status: IncidentStatus
  similarity: number | null
  prior_report_summary: string | null
}

export interface MemoryRepeatEntity {
  incident_id: number
  title: string
  risk_level: Severity
  status: IncidentStatus
  created_at: string | null
  shared: string[]
}

export interface MemoryCorrection {
  incident_id: number
  incident_title: string
  rating: 'false_positive' | 'missed_detection'
  note: string
}

export interface IncidentMemory {
  incident_id: number
  similar_past_incidents: MemorySimilarIncident[]
  repeat_hosts: MemoryRepeatEntity[]
  repeat_users: MemoryRepeatEntity[]
  recent_corrections: MemoryCorrection[]
}

export interface AgentProgressEvent {
  type: 'started' | 'agent_completed' | 'completed' | 'failed' | 'error'
  run_id?: number
  agent?: string
  message?: string | null
  error?: string
}

export interface AgentRunListItem extends AgentRunSummary {
  incident_title: string | null
}

export type GraphNodeLabel = 'Host' | 'User' | 'IP' | 'Incident' | 'Indicator' | 'Tag' | 'Source'
export type GraphEdgeType = 'ACCESSED' | 'CONNECTED_TO' | 'PART_OF' | 'TAGGED_AS' | 'REPORTED_BY' | 'MATCHED_IN'

export interface GraphNode {
  key: string
  label: GraphNodeLabel
  name?: string
  address?: string
  id?: number
  title?: string
  risk_level?: Severity
  status?: IncidentStatus
  value?: string
  indicator_type?: string
  verdict?: string
  confidence?: number
}

export interface GraphEdge {
  from: string
  to: string
  type: GraphEdgeType
  count?: number
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface ConnectorPluginType {
  key: string
  display_name: string
  category: string
  config_fields: string[]
  auth_type: 'config' | 'oauth'
}

export interface ResponseActionPluginType {
  key: string
  display_name: string
  categories: ProposedActionCategory[]
  config_fields: string[]
}

export interface ConnectorInstance {
  id: number
  plugin_key: string
  name: string
  config: Record<string, string>
  enabled: boolean
  last_sync_at: string | null
  last_sync_status: 'success' | 'error' | null
  last_sync_message: string | null
  created_at: string
}

export interface ResponseActionInstance {
  id: number
  plugin_key: string
  name: string
  config: Record<string, string>
  enabled: boolean
  created_at: string
}

export interface StreamingStatus {
  queued: number
  pending: number
}

export type ThreatIndicatorType = 'ip' | 'domain' | 'url' | 'hash'

export interface IncidentTrendDay {
  date: string
  low: number
  medium: number
  high: number
  critical: number
}

export interface ExecutiveSummary {
  open_critical_incidents: number
  open_high_incidents: number
  pending_actions: number
  running_investigations: number
  threat_indicators_tracked: number
  mean_time_to_close_hours: number | null
  incident_trend: IncidentTrendDay[]
  top_incidents: IncidentSummary[]
}

export interface ExecutiveBriefing {
  headline: string
  summary: string
  key_risks: string[]
  recommended_focus: string
}

export interface ExecutiveBriefingResponse {
  summary: ExecutiveSummary
  briefing: ExecutiveBriefing
}

export interface PredictiveAnomaly {
  host: string
  username: string
  event_count: number
  distinct_source_ips: number
  off_hours_ratio: number
  failed_login_ratio: number
  high_severity_ratio: number
  anomaly_score: number
  reasons: string[]
}

export interface PredictiveAnomalousEntities {
  status: 'ok' | 'insufficient_data'
  entities_analyzed: number
  anomalies: PredictiveAnomaly[]
}

export interface PredictiveEscalationTrend {
  direction: 'rising' | 'falling' | 'stable' | 'none' | 'insufficient_data'
  slope_per_day: number
  daily_counts: { date: string; count: number }[]
  total: number
}

export interface PredictiveRiskDrift {
  direction: 'worsening' | 'improving' | 'stable' | 'insufficient_data'
  recent_average: number | null
  prior_average: number | null
  drift: number | null
}

export interface PredictiveSummary {
  anomalous_entities: PredictiveAnomalousEntities
  privilege_escalation_trend: PredictiveEscalationTrend
  risk_drift: PredictiveRiskDrift
}

export interface PredictiveBriefing {
  headline: string
  summary: string
  likely_scenarios: string[]
  recommended_watch: string
}

export interface PredictiveBriefingResponse {
  summary: PredictiveSummary
  briefing: PredictiveBriefing
}

export interface DigitalTwinAffectedAsset {
  host: string
  criticality: string
  department: string | null
  owner: string | null
}

export interface DigitalTwinSimulation {
  entity_type: 'host' | 'user' | 'ip'
  entity_value: string
  hops: number
  reachable_hosts: number
  reachable_users: number
  related_incidents: number
  affected_assets: DigitalTwinAffectedAsset[]
  business_impact_score: number
  business_impact_pct: number
  graph: GraphData
}

export interface DigitalTwinNarrative {
  lateral_movement_narrative: string
  affected_systems: string[]
  business_impact: string
  estimated_recovery: string
  confidence: 'low' | 'medium' | 'high'
}

export interface DigitalTwinNarrativeResponse {
  simulation: DigitalTwinSimulation
  narrative: DigitalTwinNarrative
}

export interface OrganizationSettings {
  id: number
  name: string
  slug: string
  plan: string
  created_at: string
}

export interface ApiKeySummary {
  id: number
  name: string
  key_prefix: string
  acts_as_email: string | null
  created_by_email: string | null
  created_at: string
  last_used_at: string | null
  revoked: boolean
}

export interface ApiKeyCreated extends ApiKeySummary {
  key: string
}

export interface AuditLogEntryItem {
  id: number
  actor_email: string | null
  action: string
  details: Record<string, unknown>
  created_at: string
}

export interface Playbook {
  id: number
  key: string
  name: string
  description: string
  category: string
  installed: boolean
}

export interface ShiftNote {
  id: number
  author_email: string | null
  body: string
  created_at: string
}

export interface CommandCenterProposedAction extends ProposedAction {
  incident_title: string | null
}

export interface CommandCenterQueue {
  open_incidents: IncidentSummary[]
  unassigned_open_incidents: number
  pending_actions: CommandCenterProposedAction[]
}

export type FeedbackRating = 'accurate' | 'false_positive' | 'missed_detection'

export interface AnalystFeedback {
  id: number
  incident_id: number
  agent_run_id: number | null
  rating: FeedbackRating
  note: string | null
  reviewed_by_email: string | null
  created_at: string
}

export interface FeedbackTrendDay {
  date: string
  accurate: number
  false_positive: number
  missed_detection: number
}

export interface LearningStats {
  total_feedback: number
  counts: Record<FeedbackRating, number>
  accuracy_rate: number | null
  trend: FeedbackTrendDay[]
}

export interface EvaluationRatingBucket {
  rated_investigations: number
  avg_duration_seconds: number | null
  avg_detection_confidence: number | null
}

export interface EvaluationSummary {
  total_investigations: number
  avg_investigation_duration_seconds: number | null
  accuracy_correlation: Record<FeedbackRating, EvaluationRatingBucket>
  human_override_rate_pct: number | null
  proposed_actions_reviewed: number
  proposed_actions_rejected: number
}

export type ComplianceStatus = 'satisfied' | 'partial' | 'not_satisfied'

export interface ComplianceControl {
  id: number
  framework: string
  control_id: string
  title: string
  description: string
  check_key: string
  status: ComplianceStatus
  evidence: string
}

export interface ComplianceReport {
  overall_posture: string
  summary: string
  gaps: string[]
  next_steps: string
}

export interface ComplianceReportResponse {
  controls: ComplianceControl[]
  report: ComplianceReport
}

export interface ThreatIndicator {
  id: number
  indicator: string
  indicator_type: ThreatIndicatorType
  verdict: string
  confidence: number
  source: string
  tags: string | null
  first_seen: string
  last_seen: string
}

export interface AiObservabilityFeatureRow {
  feature: string
  calls_success: number
  calls_error: number
  success_rate_pct: number | null
  avg_duration_seconds: number | null
  prompt_tokens: number
  completion_tokens: number
  estimated_cost_usd: number
}

export interface AiObservabilitySummary {
  features: AiObservabilityFeatureRow[]
  totals: {
    calls: number
    estimated_cost_usd: number
    prompt_tokens: number
    completion_tokens: number
  }
}
