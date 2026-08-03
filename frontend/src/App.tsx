import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { ThemeProvider } from './theme/ThemeContext'
import { Layout } from './components/Layout'
import { ProtectedRoute } from './components/ProtectedRoute'
import { SectionLayout } from './components/SectionLayout'
import { AIAnalystPage } from './pages/AIAnalystPage'
import { AIMarketplacePage } from './pages/AIMarketplacePage'
import { AITeamPage } from './pages/AITeamPage'
import { AiObservabilityPage } from './pages/AiObservabilityPage'
import { AssetsPage } from './pages/AssetsPage'
import { AttackGraphPage } from './pages/AttackGraphPage'
import { DashboardPage } from './pages/DashboardPage'
import { ComplianceCenterPage } from './pages/ComplianceCenterPage'
import { DigitalTwinPage } from './pages/DigitalTwinPage'
import { EnterpriseAdminPage } from './pages/EnterpriseAdminPage'
import { EventsPage } from './pages/EventsPage'
import { ExecutiveDashboardPage } from './pages/ExecutiveDashboardPage'
import { IncidentDetailPage } from './pages/IncidentDetailPage'
import { IncidentsPage } from './pages/IncidentsPage'
import { IntegrationsPage } from './pages/IntegrationsPage'
import { LearningLoopPage } from './pages/LearningLoopPage'
import { LoginPage } from './pages/LoginPage'
import { PredictiveThreatDetectionPage } from './pages/PredictiveThreatDetectionPage'
import { RegisterPage } from './pages/RegisterPage'
import { SOCCommandCenterPage } from './pages/SOCCommandCenterPage'
import { ThreatIntelPage } from './pages/ThreatIntelPage'

const INVESTIGATE_TABS = [
  { to: '/events', label: 'Events' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/assets', label: 'Assets' },
  { to: '/attack-graph', label: 'Attack Graph' },
  { to: '/digital-twin', label: 'Digital Twin' },
]

const AI_TEAM_TABS = [
  { to: '/ai-team', label: 'Team' },
  { to: '/ai-analyst', label: 'Analyst Chat' },
  { to: '/ai-observability', label: 'Observability' },
  { to: '/learning', label: 'Learning Loop' },
  { to: '/marketplace', label: 'Marketplace' },
]

const THREAT_INTEL_TABS = [
  { to: '/threat-intel', label: 'Threat Intel' },
  { to: '/predictive', label: 'Predictive' },
]

const REPORTS_TABS = [
  { to: '/executive', label: 'Executive' },
  { to: '/compliance', label: 'Compliance' },
]

const SETTINGS_TABS = [
  { to: '/integrations', label: 'Integrations' },
  { to: '/admin', label: 'Admin' },
]

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route element={<ProtectedRoute />}>
            <Route element={<Layout />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/command-center" element={<SOCCommandCenterPage />} />

              <Route element={<SectionLayout tabs={INVESTIGATE_TABS} />}>
                <Route path="/events" element={<EventsPage />} />
                <Route path="/incidents" element={<IncidentsPage />} />
                <Route path="/assets" element={<AssetsPage />} />
                <Route path="/attack-graph" element={<AttackGraphPage />} />
                <Route path="/digital-twin" element={<DigitalTwinPage />} />
              </Route>
              <Route path="/incidents/:id" element={<IncidentDetailPage />} />

              <Route element={<SectionLayout tabs={AI_TEAM_TABS} />}>
                <Route path="/ai-team" element={<AITeamPage />} />
                <Route path="/ai-analyst" element={<AIAnalystPage />} />
                <Route path="/ai-observability" element={<AiObservabilityPage />} />
                <Route path="/learning" element={<LearningLoopPage />} />
                <Route path="/marketplace" element={<AIMarketplacePage />} />
              </Route>

              <Route element={<SectionLayout tabs={THREAT_INTEL_TABS} />}>
                <Route path="/threat-intel" element={<ThreatIntelPage />} />
                <Route path="/predictive" element={<PredictiveThreatDetectionPage />} />
              </Route>

              <Route element={<SectionLayout tabs={REPORTS_TABS} />}>
                <Route path="/executive" element={<ExecutiveDashboardPage />} />
                <Route path="/compliance" element={<ComplianceCenterPage />} />
              </Route>

              <Route element={<SectionLayout tabs={SETTINGS_TABS} />}>
                <Route path="/integrations" element={<IntegrationsPage />} />
                <Route path="/admin" element={<EnterpriseAdminPage />} />
              </Route>
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  )
}
