import { driver, type DriveStep } from 'driver.js'
import 'driver.js/dist/driver.css'
import { useCallback } from 'react'
import { useNavigate } from 'react-router-dom'

const SEEN_KEY = 'sentraops-tour-seen'

// Every step anchors to a real, always-mounted element (Layout's sidebar/
// header persist across every route) or a Dashboard-only element - the
// dashboard ones are why startTour() navigates to "/" first, so the tour
// works identically no matter which page it's launched from.
const STEPS: DriveStep[] = [
  {
    element: '[data-tour="brand"]',
    popover: {
      title: 'Welcome to SentraOps',
      description:
        "A quick tour of the real SOC platform underneath - everything here is wired to a real backend, not sample data. Use the arrow keys or the buttons below to move through it, and Esc to skip.",
      side: 'bottom',
      align: 'start',
    },
  },
  {
    element: '[data-tour="nav-dashboard"]',
    popover: {
      title: 'Dashboard',
      description: 'Live overview - threat posture, recent incidents, and a real event-volume trend, all computed from your actual data.',
      side: 'right',
    },
  },
  {
    element: '[data-tour="nav-investigate"]',
    popover: {
      title: 'Investigate',
      description: 'Events, Incidents, Assets, the Attack Graph, and Digital Twin simulation all live here as tabs.',
      side: 'right',
    },
  },
  {
    element: '[data-tour="nav-ai-team"]',
    popover: {
      title: 'AI Team',
      description: 'The 6-agent investigation pipeline, chat, learning loop, and playbook marketplace.',
      side: 'right',
    },
  },
  {
    element: '[data-tour="nav-reports"]',
    popover: {
      title: 'Reports',
      description: 'Executive briefings and compliance mapping (NIST/MITRE/CIS/PCI), generated from what you’ve actually ingested.',
      side: 'right',
    },
  },
  {
    element: '[data-tour="search"]',
    popover: {
      title: 'Search everything',
      description: 'One box searches across events, incidents, and assets at once.',
      side: 'bottom',
      align: 'end',
    },
  },
  {
    element: '[data-tour="notifications"]',
    popover: {
      title: 'Notifications',
      description: 'Real alerts - new incidents and assignments - polled from the backend, not simulated.',
      side: 'bottom',
      align: 'end',
    },
  },
  {
    element: '[data-tour="user-menu"]',
    popover: {
      title: 'Your account',
      description: 'Switch between light/dark theme, see your org’s invite code, and log out from here. You can restart this tour anytime from this menu too.',
      side: 'top',
      align: 'start',
    },
  },
  {
    element: '[data-tour="simulate-button"]',
    popover: {
      title: 'See it work end to end',
      description:
        'This one button ingests a real synthetic attack, correlates it into an incident, runs the full AI investigation, and syncs the attack graph - the fastest way to see the whole platform populated with real data.',
      side: 'bottom',
    },
  },
  {
    element: '[data-tour="ai-analyst-panel"]',
    popover: {
      title: 'AI Analyst status',
      description: 'Shows your most recent real investigation - or an honest "no investigations yet" if you haven’t run one.',
      side: 'left',
    },
  },
]

export function useAppTour(canAct: boolean) {
  const navigate = useNavigate()

  const startTour = useCallback(() => {
    // Set on start, not on dismiss - Escape/click-outside don't reliably
    // fire driver.js's onDestroyed callback, which left the auto-tour
    // re-launching on every reload until actually finished or closed via
    // the X button. Marking "seen" here means the tour launches at most
    // once automatically, however it's exited.
    localStorage.setItem(SEEN_KEY, 'true')
    navigate('/')
    // The simulate button only renders for admin/analyst roles (viewers
    // can't trigger it) - drop that one step rather than have driver.js
    // fail to find an element that legitimately isn't on the page.
    const steps = canAct ? STEPS : STEPS.filter((s) => s.element !== '[data-tour="simulate-button"]')
    // Dashboard-only steps need their elements mounted before driver.js
    // can measure them - one frame after navigation is enough since the
    // route change is synchronous client-side rendering, not a network wait.
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        driver({
          showProgress: true,
          allowClose: true,
          steps,
        }).drive()
      })
    })
  }, [navigate, canAct])

  return { startTour }
}

export function hasSeenTour(): boolean {
  return localStorage.getItem(SEEN_KEY) === 'true'
}
